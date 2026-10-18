/*
 * collector_image_load.cpp - ETW-based DLL/driver image load monitor.
 *
 * Uses the Microsoft-Windows-Kernel-Image ETW provider
 * ({EDD08926-8248-4140-A89E-2A9A6F7B0E68}) to capture image load
 * and unload events. Emits EDR_EVT_IMAGE_LOAD events with the loaded
 * image path, base address, size, checksum, and compile timestamp.
 *
 * A bounded thread pool renders events off the ETW callback thread,
 * mirroring the architecture of SecurityLogCollector.
 */
#include <windows.h>
#include <tdh.h>

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "etw_health.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace edr {

/* Microsoft-Windows-Kernel-Image provider GUID */
static const GUID kImageProvider = {
    0xEDD08926, 0x8248, 0x4140,
    {0xA8, 0x9E, 0x2A, 0x9A, 0x6F, 0x7B, 0x0E, 0x68}
};

class ImageLoadCollector : public ICollector {
public:
    explicit ImageLoadCollector(uint32_t queueCapacity)
        : m_queueCapacity(queueCapacity),
          m_sessionName(L"EDR-ImgLoad-" + std::to_wstring(GetCurrentProcessId())) {}

    ~ImageLoadCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        if (bus == nullptr) return false;
        m_bus.store(bus);
        m_stop.store(false);

        if (!StartEtwSession()) {
            std::fprintf(stderr,
                "[edr-image-load] ETW unavailable; image load disabled\n");
            m_bus.store(nullptr);
            return false;
        }

        for (uint32_t i = 0; i < 2; ++i) {
            m_workers.emplace_back(&ImageLoadCollector::WorkerLoop, this);
        }

        try {
            m_thread = std::thread(&ImageLoadCollector::Run, this);
        } catch (...) {
            StopWorkers();
            CloseTrace(m_traceHandle);
            m_traceHandle = 0;
            StopEtwSession();
            m_bus.store(nullptr);
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        StopEtwSession();
        if (m_traceHandle && m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(m_traceHandle);
            m_traceHandle = 0;
        }
        if (m_thread.joinable()) m_thread.join();
        StopWorkers();
        m_bus.store(nullptr);

        if (m_processed.load() > 0) {
            std::fprintf(stderr,
                "[edr-image-load] processed=%llu queued=%llu queue_dropped=%llu "
                "parse_errors=%llu pushed=%llu bus_dropped=%llu\n",
                static_cast<unsigned long long>(m_processed.load()),
                static_cast<unsigned long long>(m_queued.load()),
                static_cast<unsigned long long>(m_queueDropped.load()),
                static_cast<unsigned long long>(m_parseErrors.load()),
                static_cast<unsigned long long>(m_pushed.load()),
                static_cast<unsigned long long>(m_busDropped.load()));
        }
    }

    CollectorHealthSnapshot GetHealthSnapshot() const override {
        return SampleEtwSessionHealth(m_sessionName, m_workerActive.load());
    }

private:
    void StopEtwSession() {
        if (!m_sessionHandle) return;
        ULONG size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) +
            (m_sessionName.size() + 1) * sizeof(wchar_t));
        std::vector<uint8_t> buffer(size);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
        properties->Wnode.BufferSize = size;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy(reinterpret_cast<wchar_t*>(buffer.data() + properties->LoggerNameOffset),
               m_sessionName.c_str());
        ULONG status = ControlTraceW(m_sessionHandle, m_sessionName.c_str(),
                                      properties, EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND)
            std::fprintf(stderr, "[edr-image-load] ControlTraceW stop: %lu\n",
                         status);
        m_sessionHandle = 0;
    }

    static VOID WINAPI EventRecordCallback(EVENT_RECORD* rec) {
        auto* self = static_cast<ImageLoadCollector*>(rec->UserContext);
        if (self && !self->m_stop.load()) self->OnEventRecord(rec);
    }

    bool StartEtwSession() {
        ULONG bufSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) +
            (m_sessionName.size() + 1) * sizeof(wchar_t));
        std::vector<uint8_t> buf(bufSize);
        auto* prop = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
        prop->Wnode.BufferSize = bufSize;
        prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        prop->Wnode.ClientContext = 2;
        prop->BufferSize = 256;
        prop->MinimumBuffers = 2;
        prop->MaximumBuffers = 16;
        prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy(reinterpret_cast<wchar_t*>(reinterpret_cast<uint8_t*>(prop) +
               prop->LoggerNameOffset), m_sessionName.c_str());

        ULONG status = StartTraceW(&m_sessionHandle,
                                   m_sessionName.c_str(), prop);
        if (status != ERROR_SUCCESS) {
            std::fprintf(stderr, "[edr-image-load] StartTraceW: %lu\n",
                         status);
            return false;
        }

        ENABLE_TRACE_PARAMETERS etp = {};
        etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        etp.EnableProperty = EVENT_ENABLE_PROPERTY_SID;
        status = EnableTraceEx2(m_sessionHandle, &kImageProvider,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0, 0, INFINITE, &etp);
        if (status != ERROR_SUCCESS) {
            std::fprintf(stderr, "[edr-image-load] EnableTraceEx2: %lu\n",
                         status);
            StopEtwSession();
            return false;
        }

        EVENT_TRACE_LOGFILEW logfile = {};
        logfile.LoggerName = const_cast<LPWSTR>(m_sessionName.c_str());
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                                   PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = EventRecordCallback;
        logfile.Context = this;
        m_traceHandle = OpenTraceW(&logfile);
        if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
            std::fprintf(stderr, "[edr-image-load] OpenTraceW: %lu\n",
                         GetLastError());
            m_traceHandle = 0;
            StopEtwSession();
            return false;
        }
        return true;
    }

    void Run() {
        m_workerActive.store(true);
        ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
        m_workerActive.store(false);
    }

    static bool PropertyBytes(EVENT_RECORD* rec, const wchar_t* name,
                              std::vector<uint8_t>& value) {
        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        ULONG status = TdhGetPropertySize(rec, 0, nullptr, 1, &descriptor, &size);
        if (status != ERROR_SUCCESS || size == 0 || size > 64 * 1024) return false;
        value.resize(size);
        status = TdhGetProperty(rec, 0, nullptr, 1, &descriptor, size, value.data());
        return status == ERROR_SUCCESS;
    }

    static std::string StringProperty(EVENT_RECORD* rec,
                                      const wchar_t* name) {
        std::vector<uint8_t> bytes;
        if (!PropertyBytes(rec, name, bytes)) return {};
        if (bytes.size() >= sizeof(wchar_t) && bytes.size() % sizeof(wchar_t) == 0) {
            const wchar_t* value = reinterpret_cast<const wchar_t*>(bytes.data());
            size_t count = bytes.size() / sizeof(wchar_t);
            size_t length = 0;
            while (length < count && value[length] != L'\0') ++length;
            if (length != 0) return WideToUtf8(std::wstring(value, length).c_str());
        }
        const char* value = reinterpret_cast<const char*>(bytes.data());
        size_t length = 0;
        while (length < bytes.size() && value[length] != '\0') ++length;
        if (length != 0) return std::string(value, length);
        return {};
    }

    static bool UInt32Property(EVENT_RECORD* rec, const wchar_t* name,
                               uint32_t& value) {
        std::vector<uint8_t> bytes;
        if (!PropertyBytes(rec, name, bytes) || bytes.size() < sizeof(value))
            return false;
        memcpy(&value, bytes.data(), sizeof(value));
        return true;
    }

    static bool UInt64Property(EVENT_RECORD* rec, const wchar_t* name,
                               uint64_t& value) {
        std::vector<uint8_t> bytes;
        if (!PropertyBytes(rec, name, bytes) || bytes.size() < sizeof(value))
            return false;
        memcpy(&value, bytes.data(), sizeof(value));
        return true;
    }

    void OnEventRecord(EVENT_RECORD* rec) {
        if (rec->EventHeader.ProviderId != kImageProvider) return;
        m_processed.fetch_add(1);

        std::string imageName = StringProperty(rec, L"ImageName");
        if (imageName.empty()) {
            m_parseErrors.fetch_add(1);
            return;
        }

        uint32_t pid = 0;
        UInt32Property(rec, L"ProcessID", pid);
        uint32_t imageSize = 0;
        UInt32Property(rec, L"ImageSize", imageSize);
        uint32_t imageChecksum = 0;
        UInt32Property(rec, L"ImageCheckSum", imageChecksum);
        uint32_t timeStamp = 0;
        UInt32Property(rec, L"TimeDateStamp", timeStamp);
        uint64_t imageBase = 0;
        UInt64Property(rec, L"ImageBase", imageBase);

        /* Event ID 0 = ImageLoad, 1 = ImageUnload */
        bool isLoad = rec->EventHeader.EventDescriptor.Id == 0;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex, std::try_to_lock);
            if (!lock.owns_lock() || m_queue.size() >= m_queueCapacity ||
                m_stop.load()) {
                m_queueDropped.fetch_add(1);
                return;
            }
            ImageLoadRecord record;
            record.pid = pid;
            record.imageName = std::move(imageName);
            record.imageBase = imageBase;
            record.imageSize = imageSize;
            record.imageChecksum = imageChecksum;
            record.timeDateStamp = timeStamp;
            record.timestamp = rec->EventHeader.TimeStamp.QuadPart;
            record.isLoad = isLoad;
            m_queue.push_back(std::move(record));
            m_queued.fetch_add(1);
        }
        m_queueCv.notify_one();
    }

    void WorkerLoop() {
        for (;;) {
            ImageLoadRecord rec;
            {
                std::unique_lock<std::mutex> lock(m_queueMutex);
                m_queueCv.wait(lock, [&] {
                    return m_stop.load() || !m_queue.empty();
                });
                if (m_queue.empty()) {
                    if (m_stop.load()) return;
                    continue;
                }
                rec = std::move(m_queue.front());
                m_queue.pop_front();
            }
            EventBus* bus = m_bus.load();
            if (bus == nullptr) continue;

            Event ev;
            ev.type = EDR_EVT_IMAGE_LOAD;
            ev.ts100ns = rec.timestamp;
            ev.pid = rec.pid;
            ev.source = "etw_image_load";
            ev.fields[field::kSource] = ev.source;
            ev.fields[field::kType] = "IMAGE_LOAD";
            ev.fields[field::kImageLoadType] = rec.isLoad ? "load" : "unload";
            ev.fields[field::kImageLoaded] = rec.imageName;
            ev.fields[field::kPid] = std::to_string(rec.pid);
            if (rec.imageBase != 0)
                ev.fields[field::kImageBase] = std::to_string(rec.imageBase);
            if (rec.imageSize != 0)
                ev.fields[field::kImageSize] = std::to_string(rec.imageSize);
            if (rec.imageChecksum != 0)
                ev.fields[field::kImageChecksum] =
                    std::to_string(rec.imageChecksum);
            if (rec.timeDateStamp != 0) {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "0x%08x", rec.timeDateStamp);
                ev.fields[field::kImageCompileTime] = buf;
            }

            if (!bus->Push(ev)) m_busDropped.fetch_add(1);
            m_pushed.fetch_add(1);
        }
    }

    void StopWorkers() {
        m_stop.store(true);
        m_queueCv.notify_all();
        for (auto& worker : m_workers) {
            if (worker.joinable()) worker.join();
        }
        m_workers.clear();
    }

    struct ImageLoadRecord {
        uint32_t pid = 0;
        std::string imageName;
        uint64_t imageBase = 0;
        uint32_t imageSize = 0;
        uint32_t imageChecksum = 0;
        uint32_t timeDateStamp = 0;
        uint64_t timestamp = 0;
        bool isLoad = true;
    };

    size_t m_queueCapacity;
    std::atomic<EventBus*> m_bus{nullptr};
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_workerActive{false};
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    std::wstring m_sessionName;
    std::thread m_thread;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    std::deque<ImageLoadRecord> m_queue;
    std::vector<std::thread> m_workers;
    std::atomic<uint64_t> m_processed{0};
    std::atomic<uint64_t> m_queued{0};
    std::atomic<uint64_t> m_queueDropped{0};
    std::atomic<uint64_t> m_parseErrors{0};
    std::atomic<uint64_t> m_pushed{0};
    std::atomic<uint64_t> m_busDropped{0};
};

ICollector* CreateImageLoadCollector(uint32_t queueCapacity) {
    return new ImageLoadCollector(queueCapacity);
}

} // namespace edr

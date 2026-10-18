/*
 * event_log_bookmark.h - opt-in, ordered durable bookmarks for WinEvt pulls.
 *
 * One store belongs to one subscription stream (channel plus filter), not
 * merely to an Event Log channel: separate filtered subscriptions on Security
 * or RDP must never share a cursor.
 */
#ifndef EDR_EVENT_LOG_BOOKMARK_H
#define EDR_EVENT_LOG_BOOKMARK_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <windows.h>
#include <winevt.h>

namespace edr {

struct Event;

struct EventLogReplayOptions {
    bool enabled = false;
    /* Put replay state below a trusted parent directory. The configured leaf
     * is created with, or must already have, a protected current-owner-only
     * DACL; all mutable path components are held without delete sharing during
     * checkpoint I/O. A parent authorized to remove that leaf while the
     * collector is inactive remains an operator-controlled trust boundary. */
    std::wstring checkpointDirectory;
    /* Zero means use the collector's queue plus worker in-flight bound. Any
     * configured value is clamped to that per-collector maximum. */
    size_t maxPendingRecords = 0;
};

class EventLogBookmarkStore {
public:
    using Token = uint64_t;

    enum class State {
        Disabled,
        Empty,
        Ready,
        Gap,
        Corrupt,
        Reset,
        PersistenceFailure,
        Unavailable,
    };

    /* The WinEvt seam lets tests exercise token ordering and replay policy
     * without depending on live event channels. The file ACL/atomic path stays
     * real in those tests. Empty functions select the Windows API defaults. */
    struct WinEvtApi {
        std::function<EVT_HANDLE(const wchar_t*)> createBookmark;
        std::function<bool(EVT_HANDLE, EVT_HANDLE)> updateBookmark;
        std::function<bool(EVT_HANDLE, std::wstring&)> renderBookmark;
        std::function<bool(EVT_HANDLE, std::wstring&, uint64_t&)> eventIdentity;
        std::function<void(EVT_HANDLE)> close;
    };

    struct Status {
        bool enabled = false;
        bool available = false;
        State state = State::Disabled;
        uint64_t lastObservedRecordId = 0;
        uint64_t lastCommittedRecordId = 0;
        size_t pending = 0;
        std::string lastError;
    };

    using CheckpointDirectoryOpenedFn = std::function<void(HANDLE)>;

    EventLogBookmarkStore(std::wstring checkpointPath, std::wstring channel,
                          bool enabled = false,
                          size_t maxPendingRecords = 4096,
                          WinEvtApi winEvt = {},
                          CheckpointDirectoryOpenedFn directoryOpened = {});
    ~EventLogBookmarkStore();

    EventLogBookmarkStore(const EventLogBookmarkStore&) = delete;
    EventLogBookmarkStore& operator=(const EventLogBookmarkStore&) = delete;

    /* Missing checkpoint means first replay starts at the oldest retained
     * event. Existing files must pass DACL, format, channel and WinEvt checks. */
    bool Open(std::string* error = nullptr);

    /* Returns a WinEvt flag/bookmark pair. Caller owns and must EvtClose a
     * non-null bookmark handle. Unhealthy/corrupt stores cannot subscribe. */
    bool PrepareSubscription(DWORD& flags, EVT_HANDLE& bookmark);

    /* Capture occurs on the collector pull thread before queueing. It snapshots
     * a per-event bookmark and returns an ordered token. */
    bool Capture(EVT_HANDLE event, Token& token, std::string* error = nullptr);

    /* Acknowledge only after the source event was consumed by the sink (or
     * accepted as a semantic duplicate). Failure permanently latches a gap. */
    bool Complete(Token token, bool accepted, std::string* error = nullptr);

    /* Call for EvtSubscribe failures. Stale/invalid bookmark positions are a
     * reset state, never a future-only fallback. */
    void MarkSubscriptionError(DWORD errorCode);
    Status GetStatus() const;

    static const char* StateName(State state);

private:
    struct PendingRecord {
        uint64_t recordId = 0;
        std::wstring bookmarkXml;
        bool completed = false;
    };

    bool IsUsableState() const;
    void SetFailure(State state, const std::string& detail);
    bool LoadCheckpoint(std::string& error);
    bool SaveCheckpoint(uint64_t recordId, const std::wstring& bookmarkXml,
                        std::string& error);
    bool ParseBookmarkIdentity(const std::wstring& xml,
                               std::wstring& channel,
                               uint64_t& recordId) const;

    std::wstring m_checkpointPath;
    std::wstring m_channel;
    bool m_enabled;
    size_t m_maxPendingRecords;
    WinEvtApi m_winEvt;
    CheckpointDirectoryOpenedFn m_checkpointDirectoryOpened;
    mutable std::mutex m_mutex;
    State m_state = State::Disabled;
    uint64_t m_lastObservedRecordId = 0;
    uint64_t m_lastCommittedRecordId = 0;
    Token m_nextToken = 1;
    Token m_nextCommitToken = 1;
    std::wstring m_bookmarkXml;
    std::map<Token, PendingRecord> m_pending;
    std::string m_lastError;
    bool m_opened = false;
};

/* Owns all source bookmark tokens that contribute to one derived event, such
 * as a reassembled PowerShell ScriptBlock. The first accepted EventBus receipt
 * commits the group; failure or destruction without a receipt permanently
 * latches the stream gap. */
class EventLogBookmarkTokenGroup {
public:
    explicit EventLogBookmarkTokenGroup(
        std::shared_ptr<EventLogBookmarkStore> store);
    ~EventLogBookmarkTokenGroup();

    EventLogBookmarkTokenGroup(const EventLogBookmarkTokenGroup&) = delete;
    EventLogBookmarkTokenGroup& operator=(
        const EventLogBookmarkTokenGroup&) = delete;

    bool Add(EventLogBookmarkStore::Token token);
    bool Attach(Event& derivedEvent);
    bool Fail();
    size_t size() const;

private:
    struct State;
    std::shared_ptr<State> m_state;
};

/* Factory used by the Event Log collectors. `streamName` distinguishes
 * different filtered subscriptions of the same Windows channel. */
std::shared_ptr<EventLogBookmarkStore> CreateEventLogBookmarkStore(
    const EventLogReplayOptions& options, const wchar_t* streamName,
    const wchar_t* channel, size_t collectorInFlightBound);

} // namespace edr

#endif /* EDR_EVENT_LOG_BOOKMARK_H */

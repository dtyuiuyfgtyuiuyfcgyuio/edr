/*
 * wmi_exec_detector_tests.h - Unit test suite declaration for WmiExecDetector.
 */
#ifndef EDR_WMI_EXEC_DETECTOR_TESTS_H
#define EDR_WMI_EXEC_DETECTOR_TESTS_H

/* House style: the suite entry point lives at global scope so that
 * tests/native_tests.cpp can invoke it via RUN_SUITE(<name>) without
 * a namespace qualifier (see discovery_recon_detector_tests.h). */
void RunWmiExecDetectorTests();

#endif /* EDR_WMI_EXEC_DETECTOR_TESTS_H */

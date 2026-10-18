/*
 * lateral_transfer_detector_tests.h - Unit test suite declaration for
 * LateralTransferDetector.
 *
 * House style: the suite entry point lives at global scope so that
 * tests/native_tests.cpp can invoke it via RUN_SUITE(<name>) without a
 * namespace qualifier (see discovery_recon_detector_tests.h).
 */
#ifndef EDR_LATERAL_TRANSFER_DETECTOR_TESTS_H
#define EDR_LATERAL_TRANSFER_DETECTOR_TESTS_H

void RunLateralTransferDetectorTests();

#endif /* EDR_LATERAL_TRANSFER_DETECTOR_TESTS_H */

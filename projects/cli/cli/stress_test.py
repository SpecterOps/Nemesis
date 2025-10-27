import argparse
import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiohttp


@dataclass
class TestResult:
    success: bool
    duration: float
    error: str | None = None


class APIStressTest:
    def __init__(self, file_path: str, num_submissions: int, base_url: str = "https://localhost"):
        self.file_path = Path(file_path)
        self.num_submissions = num_submissions
        self.base_url = base_url
        self.results: list[TestResult] = []

        # Configure logging
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger(__name__)

    async def submit_single_file(self, session: aiohttp.ClientSession, submission_id: int) -> TestResult:
        start_time = time.time()

        try:
            # Prepare form data with both file and metadata
            form = aiohttp.FormData()
            form.add_field("file", open(self.file_path, "rb"), filename=self.file_path.name)

            # Create metadata
            current_time = datetime.now(UTC)
            metadata = {
                "agent_id": f"stress-test-{submission_id}",
                "project": "stress-test",
                "timestamp": current_time.isoformat(),
                "expiration": (current_time + timedelta(days=365)).isoformat(),
                "path": str(self.file_path),
            }

            # Add metadata to form
            form.add_field("metadata", json.dumps(metadata), content_type="application/json")

            # Single request to submit both file and metadata
            async with session.post(f"{self.base_url}/api/files", data=form) as response:
                if response.status != 200:
                    return TestResult(
                        success=False,
                        duration=time.time() - start_time,
                        error=f"File upload failed with status {response.status}",
                    )

                result = await response.json()
                if not result.get("object_id") or not result.get("submission_id"):
                    return TestResult(
                        success=False, duration=time.time() - start_time, error=f"Invalid response format: {result}"
                    )

            return TestResult(success=True, duration=time.time() - start_time)

        except Exception as e:
            return TestResult(success=False, duration=time.time() - start_time, error=str(e))

    async def run_stress_test(self):
        start_time = datetime.now()
        connector = aiohttp.TCPConnector(limit=100)  # Limit concurrent connections
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.submit_single_file(session, i) for i in range(self.num_submissions)]
            self.results = await asyncio.gather(*tasks)
        print(f"Files processed in: {datetime.now() - start_time} seconds")

    def print_results(self):
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]

        # Calculate statistics
        total_duration = sum(r.duration for r in self.results)
        avg_duration = total_duration / len(self.results) if self.results else 0

        self.logger.info("\nStress Test Results:")
        self.logger.info(f"Total submissions: {len(self.results)}")
        self.logger.info(f"Successful: {len(successful)}")
        self.logger.info(f"Failed: {len(failed)}")
        self.logger.info(f"Average duration: {avg_duration:.2f} seconds")
        self.logger.info(f"Total duration: {total_duration:.2f} seconds")
        self.logger.info(f"Requests per second: {len(self.results) / total_duration:.2f}")

        if failed:
            self.logger.info("\nErrors encountered:")
            for i, result in enumerate(failed):
                self.logger.error(f"Error {i + 1}: {result.error}")


def main():
    parser = argparse.ArgumentParser(description="Stress test the file upload API")
    parser.add_argument("file_path", help="Path to the file to upload")
    parser.add_argument("num_submissions", type=int, help="Number of times to submit the file")
    parser.add_argument(
        "--base-url", default="https://localhost", help="Base URL for the API (default: https://localhost)"
    )

    args = parser.parse_args()

    # Validate file exists
    if not Path(args.file_path).exists():
        print(f"Error: File {args.file_path} does not exist")
        return

    stress_test = APIStressTest(args.file_path, args.num_submissions, args.base_url)

    # Run the stress test
    asyncio.run(stress_test.run_stress_test())
    stress_test.print_results()


if __name__ == "__main__":
    main()

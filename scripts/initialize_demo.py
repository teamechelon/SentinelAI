"""Initialize or deterministically reseed the local SentinelAI database."""

from __future__ import annotations

import argparse

from sentinel_ai.services import SentinelService


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reseed", action="store_true", help="Replace existing local demo data")
    arguments = parser.parse_args()
    service = SentinelService()
    service.initialize(reseed=arguments.reseed, bootstrap_demo_data=True)
    print(f"SentinelAI database ready. Model status: {service.model_status}")


if __name__ == "__main__":
    main()

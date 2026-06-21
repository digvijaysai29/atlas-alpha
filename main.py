"""atlas entrypoint.

For Milestone 1 this simply runs the human-in-the-loop approval demo. The FastAPI Interface layer
arrives in a later milestone (see docs/architecture/ARCHITECTURE.md §Roadmap).
"""

from scripts.demo_approval import main as run_demo


def main() -> None:
    run_demo()


if __name__ == "__main__":
    main()

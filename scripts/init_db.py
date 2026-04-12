"""Initialize split-engine SQLite database."""

from engine.storage import init_db


if __name__ == "__main__":
    init_db()
    print("Initialized split-engine DB")

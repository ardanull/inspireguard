from app.collectors.agent import SentinelAgent


if __name__ == "__main__":
    agent = SentinelAgent("http://localhost:8000")
    print(agent.enroll())
    print(agent.heartbeat())

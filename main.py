from agents.data_agent import DataAgent
from agents.community_agent import CommunityAgent
from agents.misinfo_agent import MisinfoAgent

if __name__ == "__main__":
    # agent = DataAgent(
    #     subreddits=None,           # all subreddits
    #     dataset_dir="dataset",
    #     posts_per_sub=None,        # no limit per subreddit
    #     comments_per_post=None,    # no limit per post
    #     max_posts=3_000_000,            # no total post limit
    #     max_comments=3_000_000,         # no total comment limit
    #     max_scan_lines=None
    # )
    # result = agent.run()

    # Phase 2 - Community Agent
    community_agent = CommunityAgent()
    community_result = community_agent.run()

    # Phase 3 - Misinformation Detection Agent
    # misinfo_agent = MisinfoAgent(batch_size=4)
    # misinfo_result = misinfo_agent.run()
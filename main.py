from agents.data_agent import DataAgent
from agents.community_agent import CommunityAgent
from agents.stia_agent import stia_node
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

    
    community_agent = CommunityAgent()
    community_result = community_agent.run()

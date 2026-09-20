from agents.data_agent import DataAgent
from agents.community_agent import CommunityAgent
from agents.stia_agent import fetch_posts, analyze_post, print_results
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

    
    # community_agent = CommunityAgent()
    # community_result = community_agent.run()
    # Step 1 — fetch 100 posts

    SUBREDDIT = "buildapc"  # ← change to your target subreddit

    posts = fetch_posts(subreddit=SUBREDDIT)
    post_ids = [p["id"] for p in posts]

    # Step 2 — run STIA
    results = []
    for post in posts:
        result = analyze_post(post)
        results.append(result)
    print_results(results)

    # Step 3 — run Community agent with same post IDs
    agent = CommunityAgent()
    agent.run(post_ids=post_ids)
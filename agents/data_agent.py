import os
import json
import re
import pandas as pd
from utils.mongo_client import get_collection


def preprocess_posts(data):
    df = pd.DataFrame(data)
    if df.empty:
        return df
    df.drop_duplicates(subset=["post_id"], inplace=True)
    df.dropna(subset=["title"], inplace=True)
    df = df[df["title"].str.strip() != ""]
    df["content"] = df["content"].replace("", pd.NA)
    df["content"] = df["content"].fillna(df["title"])
    df["content"] = df["content"].str.lower()
    df["content"] = df["content"].apply(lambda x: re.sub(r"http\S+", "", str(x)))
    df["content"] = df["content"].apply(lambda x: re.sub(r"[^a-zA-Z0-9\s]", "", str(x)))
    df["content"] = df["content"].str.strip()
    return df


def preprocess_comments(data):
    df = pd.DataFrame(data)
    if df.empty:
        return df
    df.drop_duplicates(subset=["comment_id"], inplace=True)
    df.dropna(subset=["content"], inplace=True)
    df = df[df["content"].str.strip() != ""]
    df = df[~df["content"].isin(["[deleted]", "[removed]"])]
    if "parent_id" in df.columns:
        df["parent_id"] = df["parent_id"].fillna("").astype(str)
    df["content"] = df["content"].str.lower()
    df["content"] = df["content"].apply(lambda x: re.sub(r"http\S+", "", str(x)))
    df["content"] = df["content"].apply(lambda x: re.sub(r"[^a-zA-Z0-9\s]", "", str(x)))
    df["content"] = df["content"].str.strip()
    return df


def store(df, collection_name, drop_existing=True):
    if df.empty:
        print(f"  No data to store in {collection_name}")
        return
    collection = get_collection(collection_name)
    if drop_existing:
        collection.drop()
    records = df.to_dict(orient="records")
    collection.insert_many(records)
    print(f"  {len(records)} records stored in {collection_name}")


class DataAgent:
    def __init__(
        self,
        subreddits: list = None,
        dataset_dir: str = "dataset",
        posts_per_sub: int = 50,
        comments_per_post: int = 20,
        max_posts: int = None,
        max_comments: int = None,
        max_scan_lines: int = 200000,
    ):
        self.subreddits = [s.lower() for s in subreddits] if subreddits else None
        self.dataset_dir = dataset_dir
        self.posts_per_sub = posts_per_sub
        self.comments_per_post = comments_per_post
        self.max_posts = max_posts
        self.max_comments = max_comments
        self.max_scan_lines = max_scan_lines

    def _find_dataset_file(self, primary_names, fallback_keyword):
        for name in primary_names:
            path = os.path.join(self.dataset_dir, name)
            if os.path.exists(path):
                return path

        if os.path.exists(self.dataset_dir):
            for fname in os.listdir(self.dataset_dir):
                if fallback_keyword in fname.lower() and fname.endswith((".jsonl", ".json")):
                    return os.path.join(self.dataset_dir, fname)

        return None

    def _stream_json_file(self, filepath, max_lines=None):
        """Yields JSON objects from a JSONL file or a JSON array file."""
        if not filepath or not os.path.exists(filepath):
            return

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            first_char = f.read(1)
            f.seek(0)
            if first_char == "[":
                try:
                    data = json.load(f)
                    for item in data:
                        yield item
                    return
                except Exception:
                    f.seek(0)

            line_count = 0
            for line in f:
                line_count += 1
                if max_lines and line_count > max_lines:
                    break
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    yield json.loads(line_str)
                except json.JSONDecodeError:
                    continue

    def load_posts_from_dataset(self):
        filepath = self._find_dataset_file(
            ["reddit_posts.jsonl", "reddit_posts.json", "posts.jsonl", "posts.json"],
            "post",
        )
        if not filepath:
            print(f"  Warning: No posts dataset file found in '{self.dataset_dir}'")
            return []

        print(f"Loading posts from {filepath}...")
        posts = []
        counts_per_sub = {sub: 0 for sub in self.subreddits} if self.subreddits else {}
        total_collected = 0

        for raw_post in self._stream_json_file(filepath, max_lines=self.max_scan_lines):
            post_id = str(raw_post.get("id") or raw_post.get("post_id") or "").strip()
            if not post_id:
                continue

            sub = str(raw_post.get("subreddit") or "").strip()
            sub_lower = sub.lower()

            if self.subreddits is not None:
                if sub_lower not in self.subreddits:
                    continue
                if counts_per_sub[sub_lower] >= self.posts_per_sub:
                    if all(c >= self.posts_per_sub for c in counts_per_sub.values()):
                        break
                    continue
                counts_per_sub[sub_lower] += 1

            post = {
                "post_id": post_id,
                "title": raw_post.get("title", ""),
                "content": raw_post.get("selftext") or raw_post.get("content") or raw_post.get("body") or "",
                "author": raw_post.get("author", ""),
                "score": int(raw_post.get("score", 0)),
                "num_comments": int(raw_post.get("num_comments", 0)),
                "timestamp": int(raw_post.get("created_utc") or raw_post.get("timestamp", 0)),
                "subreddit": sub,
            }
            posts.append(post)
            total_collected += 1

            if self.max_posts and total_collected >= self.max_posts:
                break

        print(f"  Collected {len(posts)} posts from dataset.")
        return posts

    def load_comments_from_dataset(self, target_post_ids: set):
        filepath = self._find_dataset_file(
            ["reddit_comments.jsonl", "reddit_comments.json", "comments.jsonl", "comments.json"],
            "comment",
        )
        if not filepath:
            print(f"  Warning: No comments dataset file found in '{self.dataset_dir}'")
            return []

        print(f"Loading comments from {filepath}...")
        comments = []
        comments_per_post_count = {}
        total_collected = 0

        for raw_comment in self._stream_json_file(filepath, max_lines=self.max_scan_lines):
            comment_id = str(raw_comment.get("id") or raw_comment.get("comment_id") or "").strip()
            if not comment_id:
                continue

            raw_link = raw_comment.get("link_id") or raw_comment.get("post_id") or ""
            link_id = raw_link.split("_", 1)[1] if (isinstance(raw_link, str) and "_" in raw_link) else str(raw_link or "").strip()

            sub = str(raw_comment.get("subreddit") or "").strip()
            sub_lower = sub.lower()

            # Match target post IDs or subreddits if specified
            if target_post_ids:
                if link_id not in target_post_ids:
                    continue
            elif self.subreddits is not None:
                if sub_lower not in self.subreddits:
                    continue

            if link_id:
                current_post_comments = comments_per_post_count.get(link_id, 0)
                if self.comments_per_post and current_post_comments >= self.comments_per_post:
                    continue
                comments_per_post_count[link_id] = current_post_comments + 1

            raw_parent = raw_comment.get("parent_id", "")
            parent_id = raw_parent.split("_", 1)[1] if (isinstance(raw_parent, str) and "_" in raw_parent) else str(raw_parent or "").strip()

            comment = {
                "comment_id": comment_id,
                "post_id": link_id,
                "parent_id": parent_id,
                "author": raw_comment.get("author", ""),
                "content": raw_comment.get("body") or raw_comment.get("content") or "",
                "score": int(raw_comment.get("score", 0)),
                "timestamp": int(raw_comment.get("created_utc") or raw_comment.get("timestamp", 0)),
                "subreddit": sub,
            }
            comments.append(comment)
            total_collected += 1

            if self.comments_per_post and target_post_ids and all(comments_per_post_count.get(pid, 0) >= self.comments_per_post for pid in target_post_ids):
                break

            if self.max_comments and total_collected >= self.max_comments:
                break

        print(f"  Collected {len(comments)} comments from dataset.")
        return comments

    def run(self):
        print("\nData Agent started (loading from local dataset)...")

        # 1. Load posts
        raw_posts = self.load_posts_from_dataset()
        post_ids = {p["post_id"] for p in raw_posts if p.get("post_id")}

        # 2. Load comments
        raw_comments = self.load_comments_from_dataset(target_post_ids=post_ids)

        # 3. Preprocess
        print("\nPreprocessing posts and comments...")
        posts_df = preprocess_posts(raw_posts)
        comments_df = preprocess_comments(raw_comments)

        # 4. Store in MongoDB
        print("\nStoring preprocessed data into MongoDB...")
        store(posts_df, "posts", drop_existing=True)
        store(comments_df, "comments", drop_existing=True)

        print(f"\nData Agent complete.")
        print(f"Posts stored    : {len(posts_df)}")
        print(f"Comments stored : {len(comments_df)}")

        return {
            "posts": posts_df.to_dict(orient="records") if not posts_df.empty else [],
            "comments": comments_df.to_dict(orient="records") if not comments_df.empty else [],
        }
"""
Report Agent Storage — MongoDB persistence for generated reports.
"""

import os
import sys

from .config import log, MONGO_URI, MONGO_DB


def store_report(report: dict):
    """Save the full report dict to the 'reports' collection in MongoDB."""
    try:
        # Add project root to path if needed (for standalone execution)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from utils.mongo_client import get_collection
        collection = get_collection("reports")
        collection.update_one(
            {"report_id": report["report_id"]},
            {"$set": report},
            upsert=True,
        )
        log.info(f"Report saved to MongoDB — report_id={report['report_id']}")
    except ImportError:
        # Fallback: direct PyMongo connection if utils not available
        try:
            from pymongo import MongoClient
            client = MongoClient(MONGO_URI)
            db = client[MONGO_DB]
            db["reports"].update_one(
                {"report_id": report["report_id"]},
                {"$set": report},
                upsert=True,
            )
            client.close()
            log.info(f"Report saved to MongoDB (direct) — report_id={report['report_id']}")
        except Exception as e:
            log.error(f"Failed to save report to MongoDB: {e}")
    except Exception as e:
        log.error(f"Failed to save report to MongoDB: {e}")

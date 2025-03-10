import sqlite3

def get_unlabeled_queries():
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, query, predicted_label FROM feedback_log WHERE actual_label IS NULL")
    queries = cursor.fetchall()
    conn.close()
    return queries

def update_feedback(query_id, actual_label):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE feedback_log SET actual_label = ? WHERE id = ?", (actual_label, query_id))
    conn.commit()
    conn.close()

def review_feedback():
    queries = get_unlabeled_queries()
    if not queries:
        print("✅ No pending feedback!")
        return
    
    print("🔹 Pending Feedback for Review:")
    for query_id, query, predicted_label in queries:
        print(f"\nID: {query_id}")
        print(f"Query: {query}")
        print(f"Predicted Label: {predicted_label}")
        correct_label = input("🔹 Enter correct label (Safe/Malicious) or press Enter to skip: ").strip()
        if correct_label:
            update_feedback(query_id, correct_label)
            print("✅ Feedback recorded!")
    
if __name__ == "__main__":
    review_feedback()



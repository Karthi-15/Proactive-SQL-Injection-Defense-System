import sqlparse
import random
import sqlite3
from faker import Faker


fake = Faker()

class QueryMutationEngine:
    def __init__(self, query):
        self.query = query
        self.parsed_query = sqlparse.parse(query)

    def random_case_mutation(self):
        return ''.join(
            token.upper() if random.random() > 0.5 else token.lower()
            for token in self.query
        )

    def comment_injection_mutation(self):
        return self.query + " -- SQL Injection Test"

    def union_injection_mutation(self):
        return self.query + " UNION SELECT username, password FROM users;"

    def tautology_mutation(self):
        return self.query.replace("=", " OR 1=1")

    def fake_data_mutation(self):
        return self.query.replace("'admin'", f"'{fake.user_name()}'")

    def whitespace_variation_mutation(self):
        return self.query.replace(" ", "   ").replace("AND", "\nAND")

    def encoded_injection_mutation(self):
        return self.query.replace("SELECT", "S%E%L%E%C%T").replace("UNION", "U%N%I%O%N")

    def nested_query_mutation(self):
        return f"SELECT * FROM ({self.query}) AS subquery;"

    def generate_mutations(self):
        mutations = {
            "Random Case Mutation": self.random_case_mutation(),
            "Comment Injection": self.comment_injection_mutation(),
            "Union Injection": self.union_injection_mutation(),
            "Tautology Injection": self.tautology_mutation(),
            "Fake Data Mutation": self.fake_data_mutation(),
            "Whitespace Variation": self.whitespace_variation_mutation(),
            "Encoded Injection": self.encoded_injection_mutation(),
            "Nested Query Mutation": self.nested_query_mutation(),
        }
        return mutations

def test_query_on_db(query):
    """ Runs the query on the test database. """
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return f"✅ Query Executed Successfully. Result: {result}"
    except sqlite3.Error as e:
        return f"❌ Query Failed: {e}"
    finally:
        conn.close()

if __name__ == "__main__":
    user_query = input("🔹 Enter an SQL Query: ")

    qme = QueryMutationEngine(user_query)
    mutated_queries = qme.generate_mutations()

    for mutation_type, mutated_query in mutated_queries.items():
        print(f"\n🔹 {mutation_type}:")
        print(mutated_query)
        print(test_query_on_db(mutated_query))




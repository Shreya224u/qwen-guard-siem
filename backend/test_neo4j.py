from app.db.neo4j import (
    driver,
    DATABASE,
    verify_neo4j_connection,
)

try:
    verify_neo4j_connection()

    with driver.session(database=DATABASE) as session:
        result = session.run(
            "RETURN 'Neo4j connected successfully!' AS message"
        )

        record = result.single()
        print(record["message"])

except Exception as exc:
    print(f"Neo4j connection test failed: {exc}")
    raise

finally:
    driver.close()
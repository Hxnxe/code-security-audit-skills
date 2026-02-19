from django.db import connection

def execute_raw_query(sql, params=None):
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return cursor.fetchall()

def unsafe_query(user_input):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
        return cursor.fetchall()

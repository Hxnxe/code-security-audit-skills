import { Pool } from 'pg';
const pool = new Pool();

export async function executeQuery(sql: string, params: any[]) {
  const result = await pool.query(sql, params);
  return result.rows;
}

export async function rawQuery(userInput: string) {
  const result = await pool.query(`SELECT * FROM users WHERE name = '${userInput}'`);
  return result.rows;
}

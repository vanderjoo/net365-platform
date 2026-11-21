"""Net365 Autopilot: non-financial reminders and recurring task management.

This module is deliberately isolated from wallet/payment/transaction tables.
It never initiates, schedules, or executes a debit or provider transaction.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from flask import jsonify, request, g, render_template


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _user_id():
    value = getattr(g, "current_user_id", None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def init_autopilot(app, db, login_required):
    """Register isolated Autopilot schema and routes on the existing Flask app."""

    def connect():
        return db.get_db_connection()

    # Additive, idempotent schema. No existing financial table is read or changed.
    conn = connect()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS autopilot_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'personal',
                due_at TEXT,
                timezone TEXT NOT NULL DEFAULT 'Africa/Lagos',
                repeat_rule TEXT NOT NULL DEFAULT 'none',
                priority TEXT NOT NULL DEFAULT 'normal',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_autopilot_user_status_due ON autopilot_tasks(user_id, status, due_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_autopilot_user_created ON autopilot_tasks(user_id, created_at)")
        conn.commit()
    finally:
        conn.close()

    @app.get("/autopilot")
    @login_required
    def autopilot_page():
        return render_template("autopilot.html")

    @app.get("/api/autopilot/tasks")
    @login_required
    def autopilot_list_tasks():
        uid = _user_id()
        if not uid:
            return jsonify(success=False, error="Authentication required"), 401
        status = (request.args.get("status") or "").strip().lower()
        conn = connect()
        try:
            if status in {"pending", "completed", "cancelled"}:
                rows = conn.execute(
                    "SELECT * FROM autopilot_tasks WHERE user_id=? AND status=? ORDER BY COALESCE(due_at,'9999') ASC, created_at DESC",
                    (uid, status),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM autopilot_tasks WHERE user_id=? ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'completed' THEN 1 ELSE 2 END, COALESCE(due_at,'9999') ASC, created_at DESC",
                    (uid,),
                ).fetchall()
            return jsonify(success=True, tasks=[dict(row) for row in rows])
        except Exception:
            app.logger.exception("Autopilot task listing failed")
            return jsonify(success=False, error="Could not load tasks"), 500
        finally:
            conn.close()

    @app.post("/api/autopilot/tasks")
    @login_required
    def autopilot_create_task():
        uid = _user_id()
        if not uid:
            return jsonify(success=False, error="Authentication required"), 401
        data = request.get_json(silent=True) or {}
        title = str(data.get("title") or "").strip()
        if not title or len(title) > 160:
            return jsonify(success=False, error="A title of 1–160 characters is required"), 400
        description = str(data.get("description") or "").strip()
        category = str(data.get("category") or "personal").strip().lower()
        repeat_rule = str(data.get("repeat_rule") or "none").strip().lower()
        priority = str(data.get("priority") or "normal").strip().lower()
        timezone_name = str(data.get("timezone") or "Africa/Lagos").strip()[:64]
        due_at = data.get("due_at")
        allowed_categories = {"personal", "household", "business", "connectivity", "travel", "family", "other"}
        allowed_repeats = {"none", "daily", "weekly", "monthly", "yearly"}
        allowed_priorities = {"low", "normal", "high"}
        if category not in allowed_categories:
            return jsonify(success=False, error="Invalid category"), 400
        if repeat_rule not in allowed_repeats:
            return jsonify(success=False, error="Invalid repeat rule"), 400
        if priority not in allowed_priorities:
            return jsonify(success=False, error="Invalid priority"), 400
        if due_at:
            try:
                parsed = datetime.fromisoformat(str(due_at).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    return jsonify(success=False, error="Due date must include a timezone offset"), 400
                due_at = parsed.isoformat(timespec="minutes")
            except ValueError:
                return jsonify(success=False, error="Invalid due date"), 400
        task_id, now = str(uuid.uuid4()), _now()
        conn = connect()
        try:
            conn.execute("""INSERT INTO autopilot_tasks
                (id,user_id,title,description,category,due_at,timezone,repeat_rule,priority,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)""",
                (task_id, uid, title, description[:2000], category, due_at, timezone_name, repeat_rule, priority, now, now))
            conn.commit()
            row = conn.execute("SELECT * FROM autopilot_tasks WHERE id=? AND user_id=?", (task_id, uid)).fetchone()
            return jsonify(success=True, task=dict(row)), 201
        except Exception:
            conn.rollback()
            app.logger.exception("Autopilot task creation failed")
            return jsonify(success=False, error="Could not create task"), 500
        finally:
            conn.close()

    @app.patch("/api/autopilot/tasks/<task_id>")
    @login_required
    def autopilot_update_task(task_id):
        uid = _user_id()
        data = request.get_json(silent=True) or {}
        allowed = {"title", "description", "category", "due_at", "timezone", "repeat_rule", "priority", "status"}
        updates = {k: data[k] for k in allowed if k in data}
        if not updates:
            return jsonify(success=False, error="No supported fields supplied"), 400
        if "title" in updates:
            updates["title"] = str(updates["title"]).strip()
            if not updates["title"] or len(updates["title"]) > 160:
                return jsonify(success=False, error="Invalid title"), 400
        if "status" in updates and updates["status"] not in {"pending", "completed", "cancelled"}:
            return jsonify(success=False, error="Invalid status"), 400
        if "repeat_rule" in updates and updates["repeat_rule"] not in {"none", "daily", "weekly", "monthly", "yearly"}:
            return jsonify(success=False, error="Invalid repeat rule"), 400
        if "category" in updates and updates["category"] not in {"personal", "household", "business", "connectivity", "travel", "family", "other"}:
            return jsonify(success=False, error="Invalid category"), 400
        if "priority" in updates and updates["priority"] not in {"low", "normal", "high"}:
            return jsonify(success=False, error="Invalid priority"), 400
        if "due_at" in updates and updates["due_at"]:
            try:
                parsed = datetime.fromisoformat(str(updates["due_at"]).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError()
                updates["due_at"] = parsed.isoformat(timespec="minutes")
            except ValueError:
                return jsonify(success=False, error="Due date must be ISO format with timezone"), 400
        updates["updated_at"] = _now()
        if updates.get("status") == "completed":
            updates["completed_at"] = _now()
        elif updates.get("status") == "pending":
            updates["completed_at"] = None
        sql = ", ".join(f"{column}=?" for column in updates)
        conn = connect()
        try:
            cur = conn.execute(f"UPDATE autopilot_tasks SET {sql} WHERE id=? AND user_id=?", (*updates.values(), task_id, uid))
            conn.commit()
            if cur.rowcount == 0:
                return jsonify(success=False, error="Task not found"), 404
            row = conn.execute("SELECT * FROM autopilot_tasks WHERE id=? AND user_id=?", (task_id, uid)).fetchone()
            return jsonify(success=True, task=dict(row))
        except Exception:
            conn.rollback()
            app.logger.exception("Autopilot task update failed")
            return jsonify(success=False, error="Could not update task"), 500
        finally:
            conn.close()

    @app.delete("/api/autopilot/tasks/<task_id>")
    @login_required
    def autopilot_delete_task(task_id):
        uid = _user_id()
        conn = connect()
        try:
            cur = conn.execute("DELETE FROM autopilot_tasks WHERE id=? AND user_id=?", (task_id, uid))
            conn.commit()
            if cur.rowcount == 0:
                return jsonify(success=False, error="Task not found"), 404
            return jsonify(success=True)
        except Exception:
            conn.rollback()
            app.logger.exception("Autopilot task deletion failed")
            return jsonify(success=False, error="Could not delete task"), 500
        finally:
            conn.close()

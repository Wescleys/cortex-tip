from functools import wraps
from flask import session, redirect, url_for, flash, request
import db_system

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = db_system.get_user_by_id(user_id)
    if not user or not user['is_active']:
        session.clear()
        return None
    return user

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith('/api/'):
                return {"success": False, "error": "Sessão expirada. Por favor, faça login novamente no Cortex."}, 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.path.startswith('/api/'):
                    return {"success": False, "error": "Sessão expirada. Por favor, faça login novamente no Cortex."}, 401
                return redirect(url_for('login', next=request.url))
            if user['role'].lower() not in [r.lower() for r in allowed_roles]:
                if request.path.startswith('/api/'):
                    return {"success": False, "error": "Acesso não autorizado para o seu perfil de usuário."}, 403
                flash("Acesso não autorizado para o seu perfil de usuário.", "error")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_setup_required():
    """Retorna True se o sistema ainda não tem nenhum usuário cadastrado"""
    return db_system.count_users() == 0

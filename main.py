# uvicorn main:app --reload

# username "admin" and password "admin1234"

# http://127.0.0.1:8000/docs

# http://127.0.0.1:8000/static/index.html

import random, string
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import models, schemas, auth, database
from database import engine, get_db
from auth import get_current_user

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI Auth System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# authentication

@app.post("/api/auth/register", tags=["Auth"])
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="نام کاربری قبلا ثبت شده است")
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="ایمیل قبلا ثبت شده است")
    if user.password != user.password_confirm:
        raise HTTPException(status_code=400, detail="رمز عبور و تاییدیه مطابقت ندارند")

    hashed_pass = auth.get_password_hash(user.password)
    new_user = models.User(
        username=user.username, email=user.email, hashed_password=hashed_pass,
        first_name=user.first_name, last_name=user.last_name,
        phone_number=user.phone_number, bio=user.bio, date_of_birth=user.date_of_birth
    )
    db.add(new_user)
    db.commit()
    return {"message": "ثبت‌ نام با موفقیت انجام شد"}

@app.post("/api/auth/login")
def login(form_data: schemas.UserLogin, db: Session = Depends(get_db)):
    print(f"--- Login Attempt ---")
    print(f"Username entered: {form_data.username}")
    
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    if not user:
        print("Result: User not found in database!")
        raise HTTPException(status_code=401, detail="Wrong info")

    is_match = auth.verify_password(form_data.password, user.hashed_password)
    print(f"Password match: {is_match}")
    
    if not is_match:
        raise HTTPException(status_code=401, detail="Wrong info")
    
    token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/auth/logout", tags=["Auth"])
def logout(current_user: models.User = Depends(get_current_user)):
    return {"message": "با موفقیت خارج شدید"}

# account - user - 

@app.get("/api/auth/me", response_model=schemas.UserBase, tags=["Account"])
def read_me(current_user: models.User = Depends(get_current_user)):
    return current_user

@app.put("/api/auth/me", response_model=schemas.UserBase, tags=["Account"])
def update_me(data: schemas.UserUpdate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(current_user, key, value)
    db.commit()
    db.refresh(current_user)
    return current_user

@app.post("/api/auth/change-password", tags=["Account"])
def change_password(data: schemas.ChangePassword, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not auth.verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="رمز عبور فعلی اشتباه است")
    if data.new_password != data.new_password_confirm:
        raise HTTPException(status_code=400, detail="تاییدیه رمز جدید مطابقت ندارد")
    
    current_user.hashed_password = auth.get_password_hash(data.new_password)
    db.commit()
    return {"message": "رمز عبور تغییر کرد"}

# pass recovery

@app.post("/api/auth/forgot-password", tags=["Recovery"])
def forgot_password(data: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="کاربری با این ایمیل یافت نشد")
    
    reset_code = ''.join(random.choices(string.digits, k=6))
    new_entry = models.PasswordResetCode(user_id=user.id, code=reset_code)
    db.add(new_entry)
    db.commit()
    
    # console
    print("\n" + "="*40)
    print(f"RESET CODE FOR {user.email}: {reset_code}")
    print("="*40 + "\n")
    
    return {"message": "کد بازیابی ارسال شد (ترمینال را چک کنید)"}

@app.post("/api/auth/password-reset", tags=["Recovery"])
def reset_password(data: schemas.PasswordResetConfirm, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد")
    
    db_code = db.query(models.PasswordResetCode).filter(
        models.PasswordResetCode.user_id == user.id,
        models.PasswordResetCode.code == data.code,
        models.PasswordResetCode.is_used == False
    ).first()

    if not db_code:
        raise HTTPException(status_code=400, detail="کد نامعتبر یا استفاده شده است")
    if data.new_password != data.new_password_confirm:
        raise HTTPException(status_code=400, detail="عدم تطابق تاییدیه رمز")

    user.hashed_password = auth.get_password_hash(data.new_password)
    db_code.is_used = True
    db.commit()
    return {"message": "رمز عبور با موفقیت بازنشانی شد"}

# admin panel

def check_admin(user: models.User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    return user

@app.get("/api/admin/users", tags=["Admin"])
def get_all_users(admin: models.User = Depends(check_admin), db: Session = Depends(get_db)):
    return db.query(models.User).all()

@app.get("/api/admin/users/{user_id}", tags=["Admin"])
def get_user(user_id: int, admin: models.User = Depends(check_admin), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="کاربر یافت نشد")
    return user

@app.put("/api/admin/users/{user_id}", tags=["Admin"])
def admin_update_user(user_id: int, data: schemas.UserUpdate, admin: models.User = Depends(check_admin), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="کاربر یافت نشد")
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(user, key, value)
    db.commit()
    return {"message": "کاربر ویرایش شد"}

@app.patch("/api/admin/users/{user_id}/toggle-active", tags=["Admin"])
def toggle_user(user_id: int, admin: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    user.is_active = not user.is_active
    db.commit()
    return {"message": f"وضعیت کاربر به {'فعال' if user.is_active else 'غیرفعال'} تغییر کرد"}

# creating admin for the first time
@app.on_event("startup")
def create_admin():
    db = database.SessionLocal()
    if not db.query(models.User).filter(models.User.username == "admin").first():
        admin = models.User(
            username="admin", email="admin@test.com", 
            hashed_password=auth.get_password_hash("admin1234"),
            first_name="Admin", last_name="System", is_admin=True
        )
        db.add(admin)
        db.commit()
    db.close()

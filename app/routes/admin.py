from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models import Users
from app.schemas import User, UserUpdateRequest
from app.routes.auth import get_current_admin_user, get_password_hash

router = APIRouter(
    prefix='/admin',
    tags=['Admin']
)

# Dependency to ensure only admins can access these endpoints
AdminDep = Depends(get_current_admin_user)

@router.get("/users", response_model=List[User], summary="Get All Users")
async def get_all_users(db: Session = Depends(get_db), admin: Users = AdminDep):
    """
    Retrieves a list of all registered users.
    Only accessible by an admin user.
    """
    users = db.query(Users).order_by(Users.id).all()
    return users


@router.put("/users/{user_id}/make-admin", response_model=User, summary="Promote User to Admin")
async def make_user_admin(user_id: int, db: Session = Depends(get_db), admin: Users = AdminDep):
    """
    Promotes a regular user to an admin.
    Only accessible by an admin user.
    """
    user_to_promote = db.query(Users).filter(Users.id == user_id).first()
    if not user_to_promote:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    user_to_promote.is_admin = True
    db.commit()
    db.refresh(user_to_promote)
    return user_to_promote


@router.put("/users/{user_id}", response_model=User, summary="Update a User")
async def update_user(user_id: int, user_update: UserUpdateRequest, db: Session = Depends(get_db), admin: Users = AdminDep):
    """
    Updates a user's details (username or email).
    Only accessible by an admin user.
    """
    user_to_update = db.query(Users).filter(Users.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user_update.username:
        user_to_update.username = user_update.username
    if user_update.email:
        user_to_update.email = user_update.email
        
    db.commit()
    db.refresh(user_to_update)
    return user_to_update

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a User")
async def delete_user(user_id: int, db: Session = Depends(get_db), admin: Users = AdminDep):
    """
    Deletes a user from the database.
    Only accessible by an admin user.
    """
    user_to_delete = db.query(Users).filter(Users.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    db.delete(user_to_delete)
    db.commit()
    return None

@router.get("/users/{user_id}", response_model=User, summary="Get a Single User by ID")
async def get_user_by_id(user_id: int, db: Session = Depends(get_db), admin: Users = AdminDep):
    """
    Retrieves the details of a specific user by their ID.
    Only accessible by an admin user.
    """
    user = db.query(Users).filter(Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
from .database import Base
from sqlalchemy import Boolean, Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    avatar = Column(String)
    username = Column(String, unique=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=True)
    google_id = Column(String, unique=True, nullable=True, index=True)
    is_admin = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)

    # optional backref to the password-set row (one-to-one)
    passwords_set = relationship(
        'UserPasswordsSet', back_populates='user', uselist=False)


class UserPasswordsSet(Base):
    __tablename__ = 'password_set'

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True, index=True)
    old_hashed_password = Column(String, nullable=True)

    # relationship back to the Users row
    user = relationship('Users', back_populates='passwords_set', uselist=False)

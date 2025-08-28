from sqlalchemy import Column, Integer, String, DateTime, create_engine, Date, ForeignKey
from datetime import datetime, timezone
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String, unique=True)
    #Add these for OTP-based password reset
    reset_otp = Column(String, nullable=True)
    reset_expiry = Column(DateTime, nullable=True)


class PendingUser(Base):
    __tablename__ = 'pending_users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    first_name = Column(String)
    last_name = Column(String)
    password = Column(String)
    otp = Column(String)
    otp_expiry = Column(DateTime)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resend_count = Column(Integer, default=0)
    resend_block_until = Column(DateTime, nullable=True)
    username = Column(String, unique=True, nullable=False)


class DiaryEntry(Base):
    __tablename__ = 'diary_entries'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    date = Column(Date)
    text = Column(String)
    user = relationship("User")


# Run this in terminal or a Python shell
from models import Base
from sqlalchemy import create_engine
engine = create_engine('sqlite:///users.db')
Base.metadata.create_all(engine)

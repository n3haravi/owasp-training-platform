from sqlmodel import SQLModel, Field, Relationship
from typing import List, Optional

class ProjectAssignment(SQLModel, table=True):
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", primary_key=True)
    project_id: Optional[int] = Field(default=None, foreign_key="project.id", primary_key=True)

class DeveloperVulnerability(SQLModel, table=True):
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", primary_key=True)
    vulnerability_id: Optional[int] = Field(default=None, foreign_key="vulnerability.id", primary_key=True)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    full_name: str
    password_hash: str
    role: str  # "CISO" or "DEVELOPER"
    
    # Developer specific fields
    skill_level: Optional[str] = None  # Fresher, Intermediate, Expert
    training_status: Optional[str] = "Not Started"  # Not Started, In Progress, Completed
    progress: Optional[int] = 0  # completion percentage 0-100
    
    projects: List["Project"] = Relationship(back_populates="developers", link_model=ProjectAssignment)
    vulnerabilities_learned: List["Vulnerability"] = Relationship(back_populates="learners", link_model=DeveloperVulnerability)

class Application(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    technology: str
    
    projects: List["Project"] = Relationship(back_populates="application")
    vulnerabilities: List["Vulnerability"] = Relationship(back_populates="application")

class Project(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    status: str = "Active"  # Active, Completed, Pending
    application_id: Optional[int] = Field(default=None, foreign_key="application.id")
    
    application: Optional[Application] = Relationship(back_populates="projects")
    developers: List[User] = Relationship(back_populates="projects", link_model=ProjectAssignment)

class Vulnerability(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    category: str  # OWASP category
    description: str
    remediation: str
    mitigation: str
    
    application_id: Optional[int] = Field(default=None, foreign_key="application.id")
    application: Optional[Application] = Relationship(back_populates="vulnerabilities")
    
    learners: List[User] = Relationship(back_populates="vulnerabilities_learned", link_model=DeveloperVulnerability)

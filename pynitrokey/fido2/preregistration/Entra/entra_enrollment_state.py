
from enum import Enum


class EntraEnrollmentState(Enum):
    BEGIN = 1   #move_next to setup enrollment in Entra
    ENTRA_SETUP = 2 #move_next to generate credentials on NitroKey hardware
    CREDS_ON_KEY = 3 #move_next to save credentials to Entra, and complete enrollment
    COMPLETE = 4
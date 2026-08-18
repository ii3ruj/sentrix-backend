import os

from dotenv import load_dotenv
from supabase import Client, create_client


# Load variables from .env
load_dotenv()


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")


if not SUPABASE_URL:
    raise RuntimeError(
        "SUPABASE_URL is missing from the .env file."
    )

if not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_KEY is missing from the .env file."
    )


# Create Supabase client
supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)
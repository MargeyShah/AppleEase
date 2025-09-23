from datetime import date, timedelta
import os
from pathlib import Path

def get_days_from_now(num_days: int = 365):
    """
    Calculates and returns the future date

    Returns:
        date: A date object representing the date 'num_days' from now.
    """
    future_date = date.today() + timedelta(days=num_days)
    return future_date

def cleanup_output_files(files_list: list[Path]):

    for file in files_list:
        if os.path.exists(file):
            try:
                os.remove(file)
            except OSError as e:
                print(f'File not found {file}, {e}')
        else:
            print(f'File not found, skipping {file}')

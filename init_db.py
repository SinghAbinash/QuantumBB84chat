from db import init_db
import os

if __name__ == '__main__':
    path = init_db()
    print(f'Initialized database at: {os.path.abspath(path)}')

import PyInstaller.__main__
import os
import shutil

folders_to_clean = ['build', 'dist']
for folder in folders_to_clean:
    if os.path.exists(folder):
        shutil.rmtree(folder)

icon_path = "utils/icon/icon.ico"
icon_exists = os.path.exists(icon_path)

PyInstaller.__main__.run([
    'main.py',
    '--onefile',
    '--clean',
    '--name=watcher',
    
    '--add-data=utils;utils',          
    '--icon=' + icon_path if icon_exists else '',
    '--noupx',                         
])

print("\nBuild done, check the dish folder")
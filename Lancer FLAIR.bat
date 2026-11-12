@echo off
rem FLAIR Sentinel : double-cliquer sur ce fichier pour lancer le site.
title FLAIR Sentinel
cd /d "%~dp0"

rem Le LLM tourne sur la carte graphique (le plus rapide). Si la carte est instable,
rem desactiver "Carte graphique (GPU)" dans la barre laterale du site.
set FLAIR_OLLAMA_TIMEOUT=300

rem Environnement Python : cree s'il manque ou s'il vient d'un autre PC
.venv\Scripts\python.exe --version >nul 2>&1
if not errorlevel 1 goto verifier_modules
echo Creation de l'environnement Python...
python -m venv --clear .venv
if errorlevel 1 goto erreur_python

:verifier_modules
.venv\Scripts\python.exe -c "import streamlit, sklearn, plotly, pandas, requests" >nul 2>&1
if not errorlevel 1 goto verifier_donnees
echo Installation des dependances, une seule fois, quelques minutes...
.venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto erreur_installation

:verifier_donnees
if exist data\events.csv goto lancer
echo Generation des donnees simulees...
.venv\Scripts\python.exe generate_data.py
if errorlevel 1 goto erreur_donnees

:lancer
echo.
echo Le site va s'ouvrir dans le navigateur : http://localhost:8501
echo Pour l'arreter, fermer cette fenetre.
echo.
start "" /min cmd /c "ping -n 6 127.0.0.1 >nul & start http://localhost:8501"
.venv\Scripts\python.exe -m streamlit run app.py --server.headless true --server.port 8501
echo.
echo Le site s'est arrete.
pause
exit /b 0

:erreur_python
echo.
echo Python est introuvable. Installer Python 3.11 ou plus recent depuis python.org
echo en cochant "Add Python to PATH", puis relancer ce fichier.
pause
exit /b 1

:erreur_installation
echo.
echo L'installation a echoue. Verifier la connexion Internet, puis relancer ce fichier.
pause
exit /b 1

:erreur_donnees
echo.
echo La generation des donnees a echoue : voir le message ci-dessus.
pause
exit /b 1

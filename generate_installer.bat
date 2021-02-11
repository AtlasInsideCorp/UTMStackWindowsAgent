@echo [*] Updating project...
@git pull
@echo [*] Done.

@echo [*] Updating dependencies...
@%CD%\assets\Python37\python.exe -m pip install -U pip
@%CD%\assets\Python37\python.exe -m pip install -U -r requirements.txt
@if NOT ["%errorlevel%"]==["0"] (
    pause
    exit /b %errorlevel%
)
@echo [*] Done.

@echo [*] Generating Installer...
@%CD%\compiler\ISCC.exe installer.iss
@echo [*] Done.
@pause

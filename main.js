const { app, BrowserWindow, Menu } = require('electron');
const path = require('path');

function createWindow() {
    // 1. Отключаем стандартное меню (Файл, Правка и т.д.)
    Menu.setApplicationMenu(null);

    const mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        frame: false, // 2. Убираем верхнюю рамку с крестиком
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        }
    });

    // 3. Подключаемся к вашему локальному серверу (server.js)
    // ВАЖНО: Сервер (node server.js) должен быть уже запущен!
    mainWindow.loadURL('http://localhost:3000'); 
    
    // Если вы хотите открывать инструменты разработчика:
    // mainWindow.webContents.openDevTools();
}

app.whenReady().then(() => {
    createWindow();
    app.on('activate', function () {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') app.quit();
});
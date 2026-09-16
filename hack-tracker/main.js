const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const store = require('./store');
const scheduler = require('./scraper/scheduler');
const { listSources } = require('./scraper/sources');

const REFRESH_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

let mainWindow;
let isCycleRunning = false;

function runCycle() {
  if (isCycleRunning) return Promise.resolve({ skipped: true });
  isCycleRunning = true;
  const onEntryAdded = (category) => {
    if (mainWindow) mainWindow.webContents.send('table-update', category);
  };
  return scheduler
    .runCycle(onEntryAdded)
    .catch((err) => console.error('[scraper] cycle failed:', err))
    .finally(() => { isCycleRunning = false; });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

function startScrapeLoop() {
  runCycle(); // run once immediately so the app has data on launch
  setInterval(runCycle, REFRESH_INTERVAL_MS);
}

app.whenReady().then(() => {
  store.ensureDirs();
  createWindow();
  startScrapeLoop();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('get-tables', () => Object.fromEntries(store.CATEGORIES.map((c) => [c, store.loadLiveWindowed(c)])));

ipcMain.handle('get-display-window-size', () => store.getDisplayWindowSize());
ipcMain.handle('set-display-window-size', (event, size) => store.setDisplayWindowSize(size));

ipcMain.handle('search', (event, query) => store.searchAll(query));

ipcMain.handle('list-archives', () => Object.fromEntries(store.CATEGORIES.map((c) => [c, store.listArchiveFiles(c)])));

ipcMain.handle('refresh-now', () => runCycle());
ipcMain.handle('get-stats', () => store.computeStats());
ipcMain.handle('get-sources', () => listSources());

ipcMain.handle('open-path', (event, filePath) => shell.openPath(filePath));
ipcMain.handle('open-external', (event, url) => shell.openExternal(url));

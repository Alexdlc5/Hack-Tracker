const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  getTables: () => ipcRenderer.invoke('get-tables'),
  search: (query) => ipcRenderer.invoke('search', query),
  listArchives: () => ipcRenderer.invoke('list-archives'),
  refreshNow: () => ipcRenderer.invoke('refresh-now'),
  getStats: () => ipcRenderer.invoke('get-stats'),
  getSources: () => ipcRenderer.invoke('get-sources'),
  getDisplayWindowSize: () => ipcRenderer.invoke('get-display-window-size'),
  setDisplayWindowSize: (size) => ipcRenderer.invoke('set-display-window-size', size),
  openPath: (filePath) => ipcRenderer.invoke('open-path', filePath),
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  onTableUpdate: (callback) => ipcRenderer.on('table-update', (event, category) => callback(category)),
});

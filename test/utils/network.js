const { URL } = require('url');

class NetworkModule {
  constructor(options) {
    let { modules } = options;

    let moduleNameList = Object.keys(modules);
    for (let moduleName of moduleNameList) {
      let moduleInstance = modules[moduleName];
      if (moduleInstance.setNetwork) {
        moduleInstance.setNetwork(this);
      }
    }
    this.modules = modules;
  }

  setEmitter(emitter) {
    this.emitter = emitter;
  }

  async trigger(fromModule, eventName, data, info) {
    this.emitter.emit(`network:event:${fromModule}:${eventName}`, { data, info });
  }

  get actionHandlers() {
    return {
      emit: async ({ event, data }) => {
        let eventParts = event.split(':');
        let parsedUrl = new URL(eventParts[0], 'http://localhost');
        let moduleName = parsedUrl.pathname.replace(/^\//, '');
        let eventName = eventParts[1];
        let targetFunction = this.modules[moduleName].eventHandlers[eventName];
        if (!targetFunction) {
          throw new Error(`The network ${eventName} event did not exist on the ${moduleName} module`);
        }
        return targetFunction(data);
      },
      request: async ({ procedure, data }) => {
        let procedureParts = procedure.split(':');
        let parsedUrl = new URL(procedureParts[0], 'http://localhost');
        let moduleName = parsedUrl.pathname.replace(/^\//, '');
        let actionName = procedureParts[1];
        let targetFunction = this.modules[moduleName].actionHandlers[actionName];
        if (!targetFunction) {
          throw new Error(`The network ${actionName} action did not exist on the ${moduleName} module`);
        }
        return targetFunction(data);
      }
    };
  }
}

module.exports = NetworkModule;

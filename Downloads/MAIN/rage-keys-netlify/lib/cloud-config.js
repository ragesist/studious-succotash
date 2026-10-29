// Cloud Config Module for Netlify
// Deploy to: netlify/lib/cloud-config.js

const store = require("./store");

const CloudConfig = {
  // Save a config to KV
  save: async function(userId, configName, configData) {
    if (!userId || !configName || !configData) {
      return { success: false, error: "Missing required fields" };
    }
    
    // Validate config name
    if (!/^[a-zA-Z0-9_-]{1,100}$/.test(configName)) {
      return { success: false, error: "Invalid config name. Use alphanumeric, underscore, or hyphen only" };
    }
    
    // Validate and store
    const key = `cloud-config:${userId}:${configName}`;
    const configObj = {
      name: configName,
      data: configData,
      userId: userId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    try {
      // Store in memory/database
      if (!store.cloudConfigs) store.cloudConfigs = {};
      store.cloudConfigs[key] = configObj;
      store.save();
      
      return { 
        success: true, 
        message: "Config saved successfully",
        key: key 
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },
  
  // Load a config from KV
  load: async function(userId, configName) {
    if (!userId || !configName) {
      return { success: false, error: "Missing required parameters" };
    }
    
    const key = `cloud-config:${userId}:${configName}`;
    
    try {
      if (!store.cloudConfigs) store.cloudConfigs = {};
      const config = store.cloudConfigs[key];
      
      if (!config) {
        return { success: false, error: "Config not found" };
      }
      
      return { 
        success: true, 
        configName: config.name,
        configData: config.data,
        createdAt: config.createdAt,
        updatedAt: config.updatedAt
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },
  
  // List all configs for a user
  list: async function(userId) {
    if (!userId) {
      return { success: false, error: "User ID required" };
    }
    
    try {
      if (!store.cloudConfigs) store.cloudConfigs = {};
      const userConfigs = [];
      
      for (const key in store.cloudConfigs) {
        if (key.startsWith(`cloud-config:${userId}:`)) {
          userConfigs.push({
            name: store.cloudConfigs[key].name,
            createdAt: store.cloudConfigs[key].createdAt,
            updatedAt: store.cloudConfigs[key].updatedAt
          });
        }
      }
      
      return { 
        success: true, 
        configs: userConfigs
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },
  
  // Delete a config
  delete: async function(userId, configName) {
    if (!userId || !configName) {
      return { success: false, error: "Missing required parameters" };
    }
    
    const key = `cloud-config:${userId}:${configName}`;
    
    try {
      if (!store.cloudConfigs) store.cloudConfigs = {};
      if (store.cloudConfigs[key]) {
        delete store.cloudConfigs[key];
        store.save();
        return { success: true, message: "Config deleted successfully" };
      } else {
        return { success: false, error: "Config not found" };
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
};

module.exports = CloudConfig;

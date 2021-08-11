import { AppRegistry } from 'react-native'
import App from './src/App'
import { name as appName } from './app.json'
// throw new Error(appName)

AppRegistry.registerComponent(appName, () => App)

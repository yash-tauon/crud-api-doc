const swaggerJsDoc = require('swagger-jsdoc')

const swaggerOptions = {
    swaggerDefinition:{
      info:{
        title:'customer API',
        version:1.0,
        description:"Customer API information",
        basePath: '/',
      }
    },
    apis:["./routes/**/**.js"]
  }
    
const swaggerDocs = swaggerJsDoc(swaggerOptions)

module.exports = swaggerDocs;
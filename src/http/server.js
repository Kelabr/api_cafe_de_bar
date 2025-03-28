import fastify from "fastify";
import cors from "@fastify/cors"
import fastifyCookie from "@fastify/cookie";
import router from "../routers/route.js";


const app = fastify()



app.register(router, {prefix:"api"})

app.register(cors, {
    origin:"http://localhost:3000",
    credentials:true
})

app.register(fastifyCookie)



const start = async ()=>{

    try{
        app.listen({port:3333}, ()=>{
            console.log("Server runing - http://localhost:3333")
        })
    }catch(error){
        console.error("Error start server", error)
    }
}

start()


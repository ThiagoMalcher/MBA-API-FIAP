const cfg = ()=>{
    return {
        jwt_secret:"rafael",
        jwt_expires:"1d",
        salt:10,
        db:"mongodb+srv://mbafiap:UFDhaROPAGxiWZjJ@mbafiap.83wxhok.mongodb.net/?retryWrites=true&w=majority"
    }
}
module.exports = cfg();
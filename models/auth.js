const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const authSchema = new Schema({
  name:String,
  username: String,
  password:String,
  email: String,
  mobile:String,
  address:String,
  date:Date,
  profileImage:String
 

}
, {
  versionKey: false, // This will disable the __v field
});
const AuthData = mongoose.model('auth', authSchema);
module.exports = AuthData;
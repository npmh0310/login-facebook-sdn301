const mongoose = require("mongoose");
const Schema = mongoose.Schema;
require("mongoose-currency").loadType(mongoose);
var Currency = mongoose.Types.Currency;

var toppingSchema = new Schema({
  type: {
    type: String,
    required: true,
  },
  price: {
    type: Currency,
    min: 0,
  },
});

const cakeSchema = new Schema({
  type: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  price: {
    type: Currency,
    required: true,
    min: 0,
  },
  topping: [toppingSchema],
});

var Cakes = mongoose.model("Cake", cakeSchema);
module.exports = Cakes;

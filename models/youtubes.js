const mongoose = require("mongoose");
const Schema = mongoose.Schema;
require("mongoose-currency").loadType(mongoose);

var itemSchema = new Schema({
  kind: {
    type: String,
    required: true,
  },
  etag: {
    type: String,
    required: true,
  },
  id: {
    type: {
      kind: String,
      channelId: String,
      videoId: String,
    },
    required: true,
  },
});

const pageInfoSchema = new Schema({
  totalResults: {
    type: Number,
    required: true,
  },
  resultsPerPage: {
    type: Number,
    required: true,
  },
});

const youtubeSchema = new Schema({
  kind: {
    type: String,
    required: true,
  },
  etag: {
    type: String,
    required: true,
  },
  nextPageToken: {
    type: String,
    required: true,
  },
  regionCode: {
    type: String,
    required: true,
  },
  pageInfo: pageInfoSchema,
  items: [itemSchema],
});

var Youtubes = mongoose.model("Youtube", youtubeSchema);
module.exports = Youtubes;

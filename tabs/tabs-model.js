const db = require('../database/dbConfig.js')

module.exports = {
  add,
  remove,
  update,
  getTabs,
  findTabsBy,
  findByUserId
}

function getTabs() {
  return db('tabs')
}

async function add(tab) {
  const id = await db('tabs')
    .returning('id')
    .insert(tab)

  return id
}

function findTabsBy(filter) {
  return db('tabs').where(filter)
}

function update(id, changes) {
  return db('tabs')
    .where({ id })
    .returning('*')
    .update(changes, '*')
}

function remove(id) {
  return db('tabs')
    .where({ id })
    .del()
}

function findByUserId(user_id) {
  return db('tabs').where({ user_id })
}
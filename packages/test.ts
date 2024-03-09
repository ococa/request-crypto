import { createRequestInstance } from './index'

export class HH {
  constructor() {
    console.log('hh')
  }
}

const instance = createRequestInstance({})
console.log('instance', instance)

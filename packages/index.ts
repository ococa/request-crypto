import { HH } from './test'

const hh = new HH()
console.log('hh', hh)

function hhh(x: string) {
  console.log('xx', x)
}

console.log(__DEV__)

if (!__DEV__) {
  console.log('test dead conde')
}

hhh('asdf')

export { hhh, hh }

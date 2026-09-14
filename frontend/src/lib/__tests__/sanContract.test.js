/**
 * The browser half of the SAN contract.
 *
 * `contracts/san_contract.json` is a corpus of values and the answer
 * `backend/utils/san_parse.py` gives for each. `getSanValidationError` is
 * meant to give the same answer so that a value the page accepts is one the
 * server accepts, and a value the page refuses is one the server would have
 * refused too.
 *
 * Both used to be wrong in opposite directions on the same field: the IP
 * check was a shape test, so `999.999.999.999` went through the page and came
 * back refused, and `::ffff:192.168.1.1` was refused by the page although the
 * server takes it. `backend/tests/test_san_contract.py` reads this same file.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import { getSanValidationError } from '../sanValidate'

const here = dirname(fileURLToPath(import.meta.url))
// frontend/src/lib/__tests__ -> repo root
const contractPath = join(here, '..', '..', '..', '..', 'contracts', 'san_contract.json')
const contract = JSON.parse(readFileSync(contractPath, 'utf8'))

describe('SAN validation agrees with the server', () => {
  it('reads the same corpus the backend test reads', () => {
    expect(Object.keys(contract.types).sort()).toEqual(
      ['dns', 'email', 'ip', 'upn', 'uri'],
    )
  })

  for (const [sanType, rows] of Object.entries(contract.types)) {
    describe(sanType, () => {
      for (const { value, valid } of rows) {
        const label = value === '' ? '<empty>' : value
        it(`${valid ? 'accepts' : 'refuses'} ${label}`, () => {
          const error = getSanValidationError(sanType, value)
          expect(
            error === null,
            `${sanType} ${JSON.stringify(value)}: the corpus says ${
              valid ? 'valid' : 'refused'
            } and the page said ${JSON.stringify(error)}`,
          ).toBe(valid)
        })
      }
    })
  }
})

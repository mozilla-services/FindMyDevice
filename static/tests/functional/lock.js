/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'intern!bdd',
  'intern/chai!expect',
  'require'
], function (bdd, expect, require) {
  with(bdd) {
    describe('lock', function () {
      it('should lock the device', function () {
        return this.remote
          .get('http://localhost:8000/')
          // Open lock dialog
          command.findByCssSelector('.button.lost-mode a')
            .click()
          .end()
          // Modal context
          .findById('modal')
            // Fill out the note field
            .findByCssSelector('textarea.note')
              .type('This is a note')
            .end()
            // Click the next button
            .findByCssSelector('button.next')
              .click()
            .end()
            // Fill out the first passcode field
            .findByCssSelector('input.passcode-1')
              .type('1234')
            .end()
            // Fill out the second (confirmation) passcode field
            .findByCssSelector('input.passcode-2')
              .type('1234')
            .end()
            // Click Lock Device
            .findByCssSelector('button.activate')
              .click()
            .end()
          .end();
          // Wait for confirmation
          // .findByCssSelector('#notifier.active')
          //   .text()
          //   .then(function (text) {
          //     expect(text).to.equal('Your device is locked.');
          //   })
          // .end();
      });

      it('should allow an optional notes field', function () {
        return this.remote
          .get('http://localhost:8000/')
          // Open lock dialog
          command.findByCssSelector('.button.lost-mode a')
            .click()
          .end()
          // Modal context
          .findById('modal')
            // Fill out the note field
            .findByCssSelector('textarea.note')
              // Type nothing to prove it's optional
              .type('')
            .end()
            // Click the next button
            .findByCssSelector('button.next')
              .click()
            .end()
            // Confirm we transitioned to step 2 by finding the passcode field
            .findByCssSelector('input.passcode-1')
            .end()
          .end();
      });

      it('should require passcodes', function () {
        return this.remote
          .get('http://localhost:8000/')
          // Open lock dialog
          command.findByCssSelector('.button.lost-mode a')
            .click()
          .end()
          // Modal context
          .findById('modal')
            // Click the next button
            .findByCssSelector('button.next')
              .click()
            .end()
            // Click Lock Device (which is expected to fail due to validation)
            .findByCssSelector('button.activate')
              .click()
            .end()
            // Confirm that error message states that passcode is required
            .findByCssSelector('input.passcode-1 + ul.parsley-errors-list li')
              .text()
              .then(function (text) {
                expect(text).to.equal('Passcode is required.')
              })
            .end()
            // Confirm that error message states that passcode is required
            .findByCssSelector('input.passcode-2 + ul.parsley-errors-list li')
              .text()
              .then(function (text) {
                expect(text).to.equal('Passcode is required.')
              })
            .end()
          .end();
      });

      it('should require numeric passcodes', function () {
        return this.remote
          .get('http://localhost:8000/')
          // Open lock dialog
          command.findByCssSelector('.button.lost-mode a')
            .click()
          .end()
          // Modal context
          .findById('modal')
            // Click the next button
            .findByCssSelector('button.next')
              .click()
            .end()
            // Fill out the first passcode field
            .findByCssSelector('input.passcode-1')
              .type('abcd')
            .end()
            // Fill out the second (confirmation) passcode field
            .findByCssSelector('input.passcode-2')
              .type('abcd')
            .end()
            // Click Lock Device (which is expected to fail due to validation)
            .findByCssSelector('button.activate')
              .click()
            .end()
            // Confirm that error message states that passcodes must be 4 digits
            .findByCssSelector('input.passcode-1 + ul.parsley-errors-list li')
              .text()
              .then(function (text) {
                expect(text).to.equal('Passcode must be 4 digits.')
              })
            .end()
            // Confirm that error message states that passcodes must be 4 digits
            .findByCssSelector('input.passcode-2 + ul.parsley-errors-list li')
              .text()
              .then(function (text) {
                expect(text).to.equal('Passcode must be 4 digits.')
              })
            .end()
          .end();
      });

      it('should require matching passcodes', function () {
        return this.remote
          .get('http://localhost:8000/')
          // Open lock dialog
          command.findByCssSelector('.button.lost-mode a')
            .click()
          .end()
          // Modal context
          .findById('modal')
            // Click the next button
            .findByCssSelector('button.next')
              .click()
            .end()
            // Fill out the first passcode field
            .findByCssSelector('input.passcode-1')
              .type('1234')
            .end()
            // Fill out the second (confirmation) passcode field
            .findByCssSelector('input.passcode-2')
              .type('4321')
            .end()
            // Click Lock Device (which is expected to fail due to validation)
            .findByCssSelector('button.activate')
              .click()
            .end()
            // Confirm that error message states that passcodes must match
            .findByCssSelector('input.passcode-2 + ul.parsley-errors-list li')
              .text()
              .then(function (text) {
                expect(text).to.equal('Passcode must match.')
              })
            .end()
          .end();
      });
    });
  }
});

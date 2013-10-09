module.exports = function(grunt) {
  'use strict';

  var buildPackage = grunt.file.readJSON('package.json');

  grunt.initConfig({
    pkg: buildPackage,
    jshint: {
      files: ['Gruntfile.js', 'lib/*.js'],
      options: {
        ignores: ['node_modules/**/*'],
        jshintrc: '.jshintrc'
      }
    },
    mochaTest: {
      test: {
        options: {
          reporter: 'spec',
          require: ['should', 'coverage/blanket'],
          ui: 'bdd'
        },
        src: ['test/**/*.js']
      },
    
      'html-cov': {
        options: {
          reporter: 'html-cov',
          quiet: true,
          captureFile: 'coverage.html'
        },
        src: ['test/**/*.js']
      },
      // The travis-cov reporter will fail the tests if the
      // coverage falls below the threshold configured in package.json
      'travis-cov': {
        options: {
          reporter: 'travis-cov'
        },
        src: ['test/**/*.js']
      }
    }
  });

  require('matchdep').filterDev('grunt-*').forEach(grunt.loadNpmTasks);

  grunt.registerTask('default', 'Developer Build', ['jshint', 'mochaTest']);

};
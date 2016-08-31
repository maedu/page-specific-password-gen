'use strict'

const gulp = require('gulp');

const concat = require('gulp-concat');
const uglify = require('gulp-uglify');
const debug = require('gulp-debug');
const sourcemaps = require('gulp-sourcemaps');

const jasmine = require('gulp-jasmine');

gulp.task('default', ['scriptsMinified', 'scriptsNormal'], function() {
});

gulp.task('scriptsMinified', function() {
  return gulp.src(['src/**/*.js'])
    .pipe(sourcemaps.init())
    .pipe(concat('page-specific-password-gen.min.js'))
    .pipe(uglify())
    .pipe(sourcemaps.write('./', {
      sourceMappingURL: function(file) {
        return file.relative + '.map';
      }
    }))
    .pipe(gulp.dest('dist'));
});

gulp.task('scriptsNormal', function() {
  return gulp.src(['src/**/*.js'])
    .pipe(debug())
    .pipe(sourcemaps.init())
    .pipe(concat('page-specific-password-gen.js'))
    .pipe(sourcemaps.write('./', {
      sourceMappingURL: function(file) {
        return file.relative + '.map';
      }
    }))
    .pipe(gulp.dest('dist'));
});

gulp.task('test', function() {
  return gulp.src(['test/spec/*.spec.js'])
    .pipe(jasmine());
});
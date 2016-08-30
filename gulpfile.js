'use strict'

var gulp = require('gulp');

var concat = require('gulp-concat');
var uglify = require('gulp-uglify');
var debug = require('gulp-debug');
var sourcemaps = require('gulp-sourcemaps');

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
    .pipe(sourcemaps.init())
    .pipe(concat('page-specific-password-gen.js'))
    .pipe(sourcemaps.write('./', {
      sourceMappingURL: function(file) {
        return file.relative + '.map';
      }
    }))
    .pipe(gulp.dest('dist'));
});

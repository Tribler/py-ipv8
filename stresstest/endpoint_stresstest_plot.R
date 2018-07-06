#!/usr/bin/env Rscript
pdf("plot.pdf", width=8.3, height=8)
par(mar=c(7.1, 4.1, 4.1, 10.1), xpd=TRUE)
options(scipen=999)

args = commandArgs(trailingOnly=TRUE)
path = args[1]

data_rcv_initiator = read.csv(paste(path, "synchronous_packets_received_initiator.csv", sep=""), header = TRUE)
data_rcv_counterparty = read.csv(paste(path, "synchronous_packets_received_counterparty.csv", sep=""), header = TRUE)
data_snd_initiator = read.csv(paste(path, "synchronous_packets_sent_initiator.csv", sep=""), header = TRUE)
data_snd_counterparty = read.csv(paste(path, "synchronous_packets_sent_counterparty.csv", sep=""), header = TRUE)
data_arcv_initiator = read.csv(paste(path, "asynchronous_packets_received_initiator.csv", sep=""), header = TRUE)
data_arcv_counterparty = read.csv(paste(path, "asynchronous_packets_received_counterparty.csv", sep=""), header = TRUE)
data_asnd_initiator = read.csv(paste(path, "asynchronous_packets_sent_initiator.csv", sep=""), header = TRUE)
data_asnd_counterparty = read.csv(paste(path, "asynchronous_packets_sent_counterparty.csv", sep=""), header = TRUE)

minimum_time <- min(min(data_rcv_initiator$time, data_rcv_counterparty$time), min(data_snd_initiator$time, data_snd_counterparty$time))
minimum_atime <- min(min(data_arcv_initiator$time, data_arcv_counterparty$time), min(data_asnd_initiator$time, data_asnd_counterparty$time))
packet_count <- max(data_rcv_counterparty$count)
max_time <- ceiling(max(max(data_rcv_initiator$time) - minimum_time, max(data_arcv_initiator$time) - minimum_atime))

colors <- rgb(t(col2rgb(c("red", "green"))), alpha=100, maxColorValue = 255)

plot(data_rcv_initiator$time - minimum_time, data_rcv_initiator$count, type="n", xlab="time (s)", ylab="packet count/transferred data (kB)", main="Packet Throughput", ylim=c(0,packet_count), xlim=c(0,max_time))

lines(data_rcv_initiator$time - minimum_time, data_rcv_initiator$count, col=colors[1], lwd=2, lty="solid")
lines(data_rcv_counterparty$time - minimum_time, data_rcv_counterparty$count, col=colors[2], lwd=2, lty="solid")
lines(data_snd_initiator$time - minimum_time, data_snd_initiator$count, col=colors[1], lwd=2, lty="solid")
lines(data_snd_counterparty$time - minimum_time, data_snd_counterparty$count, col=colors[2], lwd=2, lty="solid")
lines(data_arcv_initiator$time - minimum_atime, data_arcv_initiator$count, col=colors[1], lwd=2, lty="longdash")
lines(data_arcv_counterparty$time - minimum_atime, data_arcv_counterparty$count, col=colors[2], lwd=2, lty="longdash")
lines(data_asnd_initiator$time - minimum_atime, data_asnd_initiator$count, col=colors[1], lwd=2, lty="longdash")
lines(data_asnd_counterparty$time - minimum_atime, data_asnd_counterparty$count, col=colors[2], lwd=2, lty="longdash")

legend("topright", c("Synchronous", "Asynchronous"), inset=c(-0.325,0), pch = c(NA, NA), lty = c("solid","longdash"))

mtext(paste("Synchronous Average", round(max(data_rcv_initiator$count)/(max(data_rcv_initiator$time) - minimum_time), digits=2), "kbps"), side=1, line=5, font=4)
mtext(paste("Asynchronous Average", round(max(data_arcv_initiator$count)/(max(data_arcv_initiator$time) - minimum_atime), digits=2), "kbps"), side=1, line=6, font=4)

if (length(args) > 1){
old_path = args[2]
old_data_rcv_initiator = read.csv(paste(old_path, "synchronous_packets_received_initiator.csv", sep=""), header = TRUE)
old_data_rcv_counterparty = read.csv(paste(old_path, "synchronous_packets_received_counterparty.csv", sep=""), header = TRUE)
old_data_snd_initiator = read.csv(paste(old_path, "synchronous_packets_sent_initiator.csv", sep=""), header = TRUE)
old_data_snd_counterparty = read.csv(paste(old_path, "synchronous_packets_sent_counterparty.csv", sep=""), header = TRUE)
old_data_arcv_initiator = read.csv(paste(old_path, "asynchronous_packets_received_initiator.csv", sep=""), header = TRUE)
old_data_arcv_counterparty = read.csv(paste(old_path, "asynchronous_packets_received_counterparty.csv", sep=""), header = TRUE)
old_data_asnd_initiator = read.csv(paste(old_path, "asynchronous_packets_sent_initiator.csv", sep=""), header = TRUE)
old_data_asnd_counterparty = read.csv(paste(old_path, "asynchronous_packets_sent_counterparty.csv", sep=""), header = TRUE)

colors <- rgb(t(col2rgb(c("red", "green"))), alpha=10, maxColorValue = 255)
minimum_time <- min(min(old_data_rcv_initiator$time, old_data_rcv_counterparty$time), min(old_data_snd_initiator$time, old_data_snd_counterparty$time))
minimum_atime <- min(min(old_data_arcv_initiator$time, old_data_arcv_counterparty$time), min(old_data_asnd_initiator$time, old_data_asnd_counterparty$time))
graphable_old_data_rcv_initiator <- old_data_rcv_initiator[which(old_data_rcv_initiator$time-minimum_time < max_time), ]
graphable_old_data_rcv_counterparty <- old_data_rcv_counterparty[which(old_data_rcv_counterparty$time-minimum_time < max_time), ]
graphable_old_data_snd_initiator <- old_data_snd_initiator[which(old_data_snd_initiator$time-minimum_time < max_time), ]
graphable_old_data_snd_counterparty <- old_data_snd_counterparty[which(old_data_snd_counterparty$time-minimum_time < max_time), ]
graphable_old_data_arcv_initiator <- old_data_arcv_initiator[which(old_data_arcv_initiator$time-minimum_atime < max_time), ]
graphable_old_data_arcv_counterparty <- old_data_arcv_counterparty[which(old_data_arcv_counterparty$time-minimum_atime < max_time), ]
graphable_old_data_asnd_initiator <- old_data_asnd_initiator[which(old_data_asnd_initiator$time-minimum_atime < max_time), ]
graphable_old_data_asnd_counterparty <- old_data_asnd_counterparty[which(old_data_asnd_counterparty$time-minimum_atime < max_time), ]
lines(graphable_old_data_rcv_initiator$time - minimum_time, graphable_old_data_rcv_initiator$count, col=colors[1], lwd=2, lty="solid")
lines(graphable_old_data_rcv_counterparty$time - minimum_time, graphable_old_data_rcv_counterparty$count, col=colors[2], lwd=2, lty="solid")
lines(graphable_old_data_snd_initiator$time - minimum_time, graphable_old_data_snd_initiator$count, col=colors[1], lwd=2, lty="solid")
lines(graphable_old_data_snd_counterparty$time - minimum_time, graphable_old_data_snd_counterparty$count, col=colors[2], lwd=2, lty="solid")
lines(graphable_old_data_arcv_initiator$time - minimum_atime, graphable_old_data_arcv_initiator$count, col=colors[1], lwd=2, lty="longdash")
lines(graphable_old_data_arcv_counterparty$time - minimum_atime, graphable_old_data_arcv_counterparty$count, col=colors[2], lwd=2, lty="longdash")
lines(graphable_old_data_asnd_initiator$time - minimum_atime, graphable_old_data_asnd_initiator$count, col=colors[1], lwd=2, lty="longdash")
lines(graphable_old_data_asnd_counterparty$time - minimum_atime, graphable_old_data_asnd_counterparty$count, col=colors[2], lwd=2, lty="longdash")

compare_ttest <- function(a, b, errors) {
time_diff_a <- diff(a$time)
time_diff_b <- diff(b$time)
data_diff_a <- diff(a$count)
data_diff_b <- diff(b$count)
speeds_a <- mapply(function(x, y) x/y, data_diff_a, time_diff_a)
speeds_b <- mapply(function(x, y) x/y, data_diff_b, time_diff_b)
# A positive value would be a speed-up, which we are fine with
if (t.test(speeds_a, speeds_b)[['statistic']][['t']]  <= -13) {
return(bitwOr(bitwShiftL(errors, 1), 1))
}
return(bitwShiftL(errors, 1))
}

errors <- 0
errors <- compare_ttest(data_rcv_initiator, old_data_rcv_initiator, errors)
errors <- compare_ttest(data_rcv_counterparty, old_data_rcv_counterparty, errors)
errors <- compare_ttest(data_snd_initiator, old_data_snd_initiator, errors)
errors <- compare_ttest(data_snd_counterparty, old_data_snd_counterparty, errors)
errors <- compare_ttest(data_arcv_initiator, old_data_arcv_initiator, errors)
errors <- compare_ttest(data_arcv_counterparty, old_data_arcv_counterparty, errors)
errors <- compare_ttest(data_asnd_initiator, old_data_asnd_initiator, errors)
errors <- compare_ttest(data_asnd_counterparty, old_data_asnd_counterparty, errors)
quit("no", errors)
}
